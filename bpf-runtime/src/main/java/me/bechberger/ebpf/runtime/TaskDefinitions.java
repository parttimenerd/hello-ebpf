/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with task
 */
@java.lang.SuppressWarnings("unused")
public final class TaskDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pid_t") int __task_pid_nr_ns(Ptr<task_struct> task, pid_type type,
      Ptr<pid_namespace> ns) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<rq> __task_rq_lock(Ptr<task_struct> p, Ptr<rq_flags> rf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<pid_namespace> task_active_pid_ns(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("task_affinity_all((const struct task_struct*)$arg1)")
  public static boolean task_affinity_all(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_bp_pinned(int cpu, Ptr<perf_event> bp, bp_type_idx type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_call_func(Ptr<task_struct> p, @OriginalName("task_call_f") Ptr<?> func,
      Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_can_attach(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_can_run_on_remote_rq(Ptr<scx_sched> sch, Ptr<task_struct> p,
      Ptr<rq> rq, boolean enforce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> task_cgroup_from_root(Ptr<task_struct> task, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_change_group_fair(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clear_jobctl_pending(Ptr<task_struct> task, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clear_jobctl_trapping(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_clock_event_add(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clock_event_del(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_clock_event_init(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clock_event_read(Ptr<perf_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clock_event_start(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_clock_event_stop(Ptr<perf_event> event, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup_cls_state> task_cls_state(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_contending(Ptr<sched_dl_entity> dl_se, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_cputime_adjusted(Ptr<task_struct> p, Ptr<java.lang. @Unsigned Long> ut,
      Ptr<java.lang. @Unsigned Long> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("task_curr((const struct task_struct*)$arg1)")
  public static int task_curr(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_current_syscall(Ptr<task_struct> target, Ptr<syscall_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_dead_fair(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_dump_owner(Ptr<task_struct> task,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<kuid_t> ruid, Ptr<kgid_t> rgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> task_early_kill(Ptr<task_struct> tsk, int force_early) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<file> task_file_seq_get_next(Ptr<bpf_iter_seq_task_file_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_file_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_file_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_file_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_file_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_fork_dl(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_fork_fair(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> task_get_cgroup1(Ptr<task_struct> tsk, int hierarchy_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_group_path(Ptr<task_group> tg, String path, int plen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_gtime(Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_h_load(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_hot(Ptr<task_struct> p, Ptr<lb_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_is_descendant(Ptr<task_struct> parent, Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_is_throttled_dl(Ptr<task_struct> p, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_is_throttled_fair(Ptr<task_struct> p, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_is_throttled_rt(Ptr<task_struct> p, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_iter_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_join_group_stop(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_mem(Ptr<seq_file> m, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_mm_cid_work(Ptr<callback_head> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_non_contending(Ptr<sched_dl_entity> dl_se) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int task_nr_scan_windows(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_assign(Ptr<task_numa_env> env, Ptr<task_struct> p, long imp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_numa_compare(Ptr<task_numa_env> env, long taskimp, long groupimp,
      boolean maymove) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_fault(int last_cpupid, int mem_node, int pages, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_find_cpu(Ptr<task_numa_env> env, long taskimp, long groupimp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_free(Ptr<task_struct> p, boolean _final) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_group(Ptr<task_struct> p, int cpupid, int flags,
      Ptr<java.lang.Integer> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pid_t") int task_numa_group_id(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_numa_migrate(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_placement(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_numa_work(Ptr<callback_head> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("task_on_scx((const struct task_struct*)$arg1)")
  public static boolean task_on_scx(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_participate_group_stop(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("task_prio((const struct task_struct*)$arg1)")
  public static int task_prio(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<rq> task_rq_lock(Ptr<task_struct> p, Ptr<rq_flags> rf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int task_scan_max(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int task_scan_start(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_sched_runtime(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_seccomp(Ptr<seq_file> m, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> task_seq_get_next(Ptr<bpf_iter_seq_task_common> common,
      Ptr<java.lang. @Unsigned Integer> tid, boolean skip_if_dup_files) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_set_jobctl_pending(Ptr<task_struct> task, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_set_syscall_user_dispatch(Ptr<task_struct> task, @Unsigned long mode,
      @Unsigned long offset, @Unsigned long len, String selector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_should_scx(int policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_size_32bit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_size_64bit(int full_addr_space) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_state(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static char task_state_to_char(Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_statm(Ptr<mm_struct> mm, Ptr<java.lang. @Unsigned Long> shared,
      Ptr<java.lang. @Unsigned Long> text, Ptr<java.lang. @Unsigned Long> data,
      Ptr<java.lang. @Unsigned Long> resident) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bpf_map> task_storage_map_alloc(Ptr<bpf_attr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_storage_map_free(Ptr<bpf_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<bpf_local_storage>> task_storage_ptr(Ptr<?> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_dl(Ptr<rq> rq, Ptr<task_struct> p, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_fair(Ptr<rq> rq, Ptr<task_struct> curr, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_idle(Ptr<rq> rq, Ptr<task_struct> curr, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_mm_cid(Ptr<rq> rq, Ptr<task_struct> curr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_rt(Ptr<rq> rq, Ptr<task_struct> p, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_scx(Ptr<rq> rq, Ptr<task_struct> curr, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_tick_stop(Ptr<rq> rq, Ptr<task_struct> curr, int queued) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_unlink_from_dsq(Ptr<task_struct> p, Ptr<scx_dispatch_q> dsq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_update_io_bitmap() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct user_regset_view*)task_user_regset_view($arg1))")
  public static Ptr<user_regset_view> task_user_regset_view(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<vm_area_struct> task_vma_seq_get_next(Ptr<bpf_iter_seq_task_vma_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_vma_seq_next(Ptr<seq_file> seq, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_vma_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> task_vma_seq_start(Ptr<seq_file> seq,
      Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_vma_seq_stop(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_vruntime_update(Ptr<rq> rq, Ptr<task_struct> p, boolean in_fi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long task_vsize(Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_wants_autogroup(Ptr<task_struct> p, Ptr<task_group> tg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_will_free_mem(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_woken_dl(Ptr<rq> rq, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_woken_rt(Ptr<rq> rq, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_woken_scx(Ptr<rq> rq, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int task_work_add(Ptr<task_struct> task, Ptr<callback_head> work,
      task_work_notify_mode notify) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean task_work_cancel(Ptr<task_struct> task, Ptr<callback_head> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<callback_head> task_work_cancel_func(Ptr<task_struct> task,
      @OriginalName("task_work_func_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("task_work_cancel_match($arg1, (_Bool (*)(struct callback_head*, void*))$arg2, $arg3)")
  public static Ptr<callback_head> task_work_cancel_match(Ptr<task_struct> task, Ptr<?> match,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_work_run() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void task_work_set_notify_irq(Ptr<irq_work> entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_struct extends Struct {
    public thread_info thread_info;

    public @Unsigned int __state;

    public @Unsigned int saved_state;

    public Ptr<?> stack;

    public @OriginalName("refcount_t") refcount_struct usage;

    public @Unsigned int flags;

    public @Unsigned int ptrace;

    public int on_cpu;

    public __call_single_node wake_entry;

    public @Unsigned int wakee_flips;

    public @Unsigned long wakee_flip_decay_ts;

    public Ptr<task_struct> last_wakee;

    public int recent_used_cpu;

    public int wake_cpu;

    public int on_rq;

    public int prio;

    public int static_prio;

    public int normal_prio;

    public @Unsigned int rt_priority;

    public sched_entity se;

    public sched_rt_entity rt;

    public sched_dl_entity dl;

    public Ptr<sched_dl_entity> dl_server;

    public sched_ext_entity scx;

    public Ptr<sched_class> sched_class;

    public rb_node core_node;

    public @Unsigned long core_cookie;

    public @Unsigned int core_occupation;

    public Ptr<task_group> sched_task_group;

    public uclamp_se @Size(2) [] uclamp_req;

    public uclamp_se @Size(2) [] uclamp;

    public sched_statistics stats;

    public hlist_head preempt_notifiers;

    public @Unsigned int btrace_seq;

    public @Unsigned int policy;

    public @Unsigned long max_allowed_capacity;

    public int nr_cpus_allowed;

    public Ptr<@OriginalName("cpumask_t") cpumask> cpus_ptr;

    public Ptr<@OriginalName("cpumask_t") cpumask> user_cpus_ptr;

    public @OriginalName("cpumask_t") cpumask cpus_mask;

    public Ptr<?> migration_pending;

    public @Unsigned short migration_disabled;

    public @Unsigned short migration_flags;

    public int rcu_read_lock_nesting;

    public rcu_special rcu_read_unlock_special;

    public list_head rcu_node_entry;

    public Ptr<rcu_node> rcu_blocked_node;

    public @Unsigned long rcu_tasks_nvcsw;

    public char rcu_tasks_holdout;

    public char rcu_tasks_idx;

    public int rcu_tasks_idle_cpu;

    public list_head rcu_tasks_holdout_list;

    public int rcu_tasks_exit_cpu;

    public list_head rcu_tasks_exit_list;

    public int trc_reader_nesting;

    public int trc_ipi_to_cpu;

    public rcu_special trc_reader_special;

    public list_head trc_holdout_list;

    public list_head trc_blkd_node;

    public int trc_blkd_cpu;

    public sched_info sched_info;

    public list_head tasks;

    public plist_node pushable_tasks;

    public rb_node pushable_dl_tasks;

    public Ptr<mm_struct> mm;

    public Ptr<mm_struct> active_mm;

    public Ptr<address_space> faults_disabled_mapping;

    public int exit_state;

    public int exit_code;

    public int exit_signal;

    public int pdeath_signal;

    public @Unsigned long jobctl;

    public @Unsigned int personality;

    public @Unsigned int sched_reset_on_fork;

    public @Unsigned int sched_contributes_to_load;

    public @Unsigned int sched_migrated;

    public @Unsigned int sched_task_hot;

    public @Unsigned int sched_remote_wakeup;

    public @Unsigned int sched_rt_mutex;

    public @Unsigned int user_dumpable;

    public @Unsigned int in_execve;

    public @Unsigned int in_iowait;

    public @Unsigned int restore_sigmask;

    public @Unsigned int in_lru_fault;

    public @Unsigned int no_cgroup_migration;

    public @Unsigned int frozen;

    public @Unsigned int use_memdelay;

    public @Unsigned int in_memstall;

    public @Unsigned int in_eventfd;

    public @Unsigned int pasid_activated;

    public @Unsigned int reported_split_lock;

    public @Unsigned int in_thrashing;

    public @Unsigned int in_nf_duplicate;

    public @Unsigned long atomic_flags;

    public restart_block restart_block;

    public @OriginalName("pid_t") int pid;

    public @OriginalName("pid_t") int tgid;

    public @Unsigned long stack_canary;

    public Ptr<task_struct> real_parent;

    public Ptr<task_struct> parent;

    public list_head children;

    public list_head sibling;

    public Ptr<task_struct> group_leader;

    public list_head ptraced;

    public list_head ptrace_entry;

    public Ptr<pid> thread_pid;

    public hlist_node @Size(4) [] pid_links;

    public list_head thread_node;

    public Ptr<completion> vfork_done;

    public Ptr<java.lang.Integer> set_child_tid;

    public Ptr<java.lang.Integer> clear_child_tid;

    public Ptr<?> worker_private;

    public @Unsigned long utime;

    public @Unsigned long stime;

    public @Unsigned long gtime;

    public prev_cputime prev_cputime;

    public vtime vtime;

    public atomic_t tick_dep_mask;

    public @Unsigned long nvcsw;

    public @Unsigned long nivcsw;

    public @Unsigned long start_time;

    public @Unsigned long start_boottime;

    public @Unsigned long min_flt;

    public @Unsigned long maj_flt;

    public posix_cputimers posix_cputimers;

    public posix_cputimers_work posix_cputimers_work;

    public Ptr<cred> ptracer_cred;

    public Ptr<cred> real_cred;

    public Ptr<cred> cred;

    public Ptr<key> cached_requested_key;

    public char @Size(16) [] comm;

    public Ptr<nameidata> nameidata;

    public sysv_sem sysvsem;

    public sysv_shm sysvshm;

    public @Unsigned long last_switch_count;

    public @Unsigned long last_switch_time;

    public Ptr<fs_struct> fs;

    public Ptr<files_struct> files;

    public Ptr<io_uring_task> io_uring;

    public Ptr<nsproxy> nsproxy;

    public Ptr<signal_struct> signal;

    public Ptr<sighand_struct> sighand;

    public sigset_t blocked;

    public sigset_t real_blocked;

    public sigset_t saved_sigmask;

    public sigpending pending;

    public @Unsigned long sas_ss_sp;

    public @Unsigned long sas_ss_size;

    public @Unsigned int sas_ss_flags;

    public Ptr<callback_head> task_works;

    public Ptr<audit_context> audit_context;

    public kuid_t loginuid;

    public @Unsigned int sessionid;

    public seccomp seccomp;

    public syscall_user_dispatch syscall_dispatch;

    public @Unsigned long parent_exec_id;

    public @Unsigned long self_exec_id;

    public @OriginalName("spinlock_t") spinlock alloc_lock;

    public @OriginalName("raw_spinlock_t") raw_spinlock pi_lock;

    public wake_q_node wake_q;

    public rb_root_cached pi_waiters;

    public Ptr<task_struct> pi_top_task;

    public Ptr<rt_mutex_waiter> pi_blocked_on;

    public Ptr<mutex> blocked_on;

    public @Unsigned long blocker;

    public @Unsigned int in_ubsan;

    public Ptr<?> journal_info;

    public Ptr<bio_list> bio_list;

    public Ptr<blk_plug> plug;

    public Ptr<reclaim_state> reclaim_state;

    public Ptr<io_context> io_context;

    public Ptr<capture_control> capture_control;

    public @Unsigned long ptrace_message;

    public Ptr<@OriginalName("kernel_siginfo_t") kernel_siginfo> last_siginfo;

    public task_io_accounting ioac;

    public @Unsigned int psi_flags;

    public @Unsigned long acct_rss_mem1;

    public @Unsigned long acct_vm_mem1;

    public @Unsigned long acct_timexpd;

    public nodemask_t mems_allowed;

    public @OriginalName("seqcount_spinlock_t") seqcount_spinlock mems_allowed_seq;

    public int cpuset_mem_spread_rotor;

    public Ptr<css_set> cgroups;

    public list_head cg_list;

    public @Unsigned int closid;

    public @Unsigned int rmid;

    public Ptr<robust_list_head> robust_list;

    public Ptr<compat_robust_list_head> compat_robust_list;

    public list_head pi_state_list;

    public Ptr<futex_pi_state> pi_state_cache;

    public mutex futex_exit_mutex;

    public @Unsigned int futex_state;

    public char @Size(4) [] perf_recursion;

    public Ptr<perf_event_context> perf_event_ctxp;

    public mutex perf_event_mutex;

    public list_head perf_event_list;

    public Ptr<perf_ctx_data> perf_ctx_data;

    public Ptr<mempolicy> mempolicy;

    public short il_prev;

    public char il_weight;

    public short pref_node_fork;

    public int numa_scan_seq;

    public @Unsigned int numa_scan_period;

    public @Unsigned int numa_scan_period_max;

    public int numa_preferred_nid;

    public @Unsigned long numa_migrate_retry;

    public @Unsigned long node_stamp;

    public @Unsigned long last_task_numa_placement;

    public @Unsigned long last_sum_exec_runtime;

    public callback_head numa_work;

    public Ptr<numa_group> numa_group;

    public Ptr<java.lang. @Unsigned Long> numa_faults;

    public @Unsigned long total_numa_faults;

    public @Unsigned long @Size(3) [] numa_faults_locality;

    public @Unsigned long numa_pages_migrated;

    public Ptr<rseq> rseq;

    public @Unsigned int rseq_len;

    public @Unsigned int rseq_sig;

    public @Unsigned long rseq_event_mask;

    public int mm_cid;

    public int last_mm_cid;

    public int migrate_from_cpu;

    public int mm_cid_active;

    public callback_head cid_work;

    public tlbflush_unmap_batch tlb_ubc;

    public Ptr<pipe_inode_info> splice_pipe;

    public page_frag task_frag;

    public Ptr<task_delay_info> delays;

    public int nr_dirtied;

    public int nr_dirtied_pause;

    public @Unsigned long dirty_paused_when;

    public int latency_record_count;

    public latency_record @Size(32) [] latency_record;

    public @Unsigned long timer_slack_ns;

    public @Unsigned long default_timer_slack_ns;

    public int curr_ret_stack;

    public int curr_ret_depth;

    public Ptr<java.lang. @Unsigned Long> ret_stack;

    public @Unsigned long ftrace_timestamp;

    public @Unsigned long ftrace_sleeptime;

    public atomic_t trace_overrun;

    public atomic_t tracing_graph_pause;

    public @Unsigned long trace_recursion;

    public @Unsigned int memcg_nr_pages_over_high;

    public Ptr<mem_cgroup> active_memcg;

    public Ptr<obj_cgroup> objcg;

    public Ptr<gendisk> throttle_disk;

    public Ptr<uprobe_task> utask;

    public @Unsigned int sequential_io;

    public @Unsigned int sequential_io_avg;

    public kmap_ctrl kmap_ctrl;

    public callback_head rcu;

    public @OriginalName("refcount_t") refcount_struct rcu_users;

    public int pagefault_disabled;

    public Ptr<task_struct> oom_reaper_list;

    public timer_list oom_reaper_timer;

    public Ptr<vm_struct> stack_vm_area;

    public @OriginalName("refcount_t") refcount_struct stack_refcount;

    public int patch_state;

    public Ptr<?> security;

    public Ptr<bpf_local_storage> bpf_storage;

    public Ptr<bpf_run_ctx> bpf_ctx;

    public Ptr<bpf_net_context> bpf_net_context;

    public Ptr<?> mce_vaddr;

    public @Unsigned long mce_kflags;

    public @Unsigned long mce_addr;

    public @Unsigned long mce_ripv;

    public @Unsigned long mce_whole_page;

    public @Unsigned long __mce_reserved;

    public callback_head mce_kill_me;

    public int mce_count;

    public llist_head kretprobe_instances;

    public llist_head rethooks;

    public callback_head l1d_flush_kill;

    public rv_task_monitor @Size(2) [] rv;

    public Ptr<user_event_mm> user_event_mm;

    public thread_struct thread;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_cputime"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_cputime extends Struct {
    public @Unsigned long stime;

    public @Unsigned long utime;

    public @Unsigned long sum_exec_runtime;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_io_accounting"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_io_accounting extends Struct {
    public @Unsigned long rchar;

    public @Unsigned long wchar;

    public @Unsigned long syscr;

    public @Unsigned long syscw;

    public @Unsigned long read_bytes;

    public @Unsigned long write_bytes;

    public @Unsigned long cancelled_write_bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_delay_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_delay_info extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public @Unsigned long blkio_start;

    public @Unsigned long blkio_delay_max;

    public @Unsigned long blkio_delay_min;

    public @Unsigned long blkio_delay;

    public @Unsigned long swapin_start;

    public @Unsigned long swapin_delay_max;

    public @Unsigned long swapin_delay_min;

    public @Unsigned long swapin_delay;

    public @Unsigned int blkio_count;

    public @Unsigned int swapin_count;

    public @Unsigned long freepages_start;

    public @Unsigned long freepages_delay_max;

    public @Unsigned long freepages_delay_min;

    public @Unsigned long freepages_delay;

    public @Unsigned long thrashing_start;

    public @Unsigned long thrashing_delay_max;

    public @Unsigned long thrashing_delay_min;

    public @Unsigned long thrashing_delay;

    public @Unsigned long compact_start;

    public @Unsigned long compact_delay_max;

    public @Unsigned long compact_delay_min;

    public @Unsigned long compact_delay;

    public @Unsigned long wpcopy_start;

    public @Unsigned long wpcopy_delay_max;

    public @Unsigned long wpcopy_delay_min;

    public @Unsigned long wpcopy_delay;

    public @Unsigned long irq_delay_max;

    public @Unsigned long irq_delay_min;

    public @Unsigned long irq_delay;

    public @Unsigned int freepages_count;

    public @Unsigned int thrashing_count;

    public @Unsigned int compact_count;

    public @Unsigned int wpcopy_count;

    public @Unsigned int irq_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_cputime_atomic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_cputime_atomic extends Struct {
    public atomic64_t utime;

    public atomic64_t stime;

    public atomic64_t sum_exec_runtime;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int pid; unsigned int fd; unsigned int flags; unsigned int buf_len; long long unsigned int buf; unsigned int prog_id; unsigned int fd_type; long long unsigned int probe_offset; long long unsigned int probe_addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_fd_query_of_bpf_attr extends Struct {
    public @Unsigned int pid;

    public @Unsigned int fd;

    public @Unsigned int flags;

    public @Unsigned int buf_len;

    public @Unsigned long buf;

    public @Unsigned int prog_id;

    public @Unsigned int fd_type;

    public @Unsigned long probe_offset;

    public @Unsigned long probe_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int tid; unsigned int pid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_of_anon_member_of_iter_of_anon_member_of_bpf_link_info extends Struct {
    public @Unsigned int tid;

    public @Unsigned int pid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { enum bpf_iter_task_type type; unsigned int pid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_of_bpf_iter_aux_info extends Struct {
    public bpf_iter_task_type type;

    public @Unsigned int pid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum task_work_notify_mode"
  )
  public enum task_work_notify_mode implements Enum<task_work_notify_mode>, TypedEnum<task_work_notify_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code TWA_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TWA_NONE"
    )
    TWA_NONE,

    /**
     * {@code TWA_RESUME = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TWA_RESUME"
    )
    TWA_RESUME,

    /**
     * {@code TWA_SIGNAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TWA_SIGNAL"
    )
    TWA_SIGNAL,

    /**
     * {@code TWA_SIGNAL_NO_IPI = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TWA_SIGNAL_NO_IPI"
    )
    TWA_SIGNAL_NO_IPI,

    /**
     * {@code TWA_NMI_CURRENT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TWA_NMI_CURRENT"
    )
    TWA_NMI_CURRENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_group extends Struct {
    public cgroup_subsys_state css;

    public int idle;

    public Ptr<Ptr<sched_entity>> se;

    public Ptr<Ptr<cfs_rq>> cfs_rq;

    public @Unsigned long shares;

    public @OriginalName("atomic_long_t") atomic64_t load_avg;

    public scx_task_group scx;

    public callback_head rcu;

    public list_head list;

    public Ptr<task_group> parent;

    public list_head siblings;

    public list_head children;

    public Ptr<autogroup> autogroup;

    public cfs_bandwidth cfs_bandwidth;

    public @Unsigned int @Size(2) [] uclamp_pct;

    public uclamp_se @Size(2) [] uclamp_req;

    public uclamp_se @Size(2) [] uclamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_numa_env"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_numa_env extends Struct {
    public Ptr<task_struct> p;

    public int src_cpu;

    public int src_nid;

    public int dst_cpu;

    public int dst_nid;

    public int imb_numa_nr;

    public numa_stats src_stats;

    public numa_stats dst_stats;

    public int imbalance_pct;

    public int dist;

    public Ptr<task_struct> best_task;

    public long best_imp;

    public int best_cpu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int tid; unsigned int pid; unsigned int pid_fd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_of_bpf_iter_link_info extends Struct {
    public @Unsigned int tid;

    public @Unsigned int pid;

    public @Unsigned int pid_fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_struct__safe_rcu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_struct__safe_rcu extends Struct {
    public Ptr<@OriginalName("cpumask_t") cpumask> cpus_ptr;

    public Ptr<css_set> cgroups;

    public Ptr<task_struct> real_parent;

    public Ptr<task_struct> group_leader;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_security_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_security_struct extends Struct {
    public avdcache_of_task_security_struct avdcache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct task_smack"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_smack extends Struct {
    public Ptr<smack_known> smk_task;

    public Ptr<smack_known> smk_forked;

    public Ptr<smack_known> smk_transmuted;

    public list_head smk_rules;

    public mutex smk_rules_lock;

    public list_head smk_relabel;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const struct tomoyo_path_info*; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class task_of_param_of_tomoyo_request_info extends Struct {
    public Ptr<tomoyo_path_info> domainname;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct rseq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class rseq extends Struct {
    public @Unsigned int cpu_id_start;

    public @Unsigned int cpu_id;

    public @Unsigned long rseq_cs;

    public @Unsigned int flags;

    public @Unsigned int node_id;

    public @Unsigned int mm_cid;

    public char @Size(0) [] end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct seccomp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class seccomp extends Struct {
    public int mode;

    public atomic_t filter_count;

    public Ptr<seccomp_filter> filter;
  }
}
