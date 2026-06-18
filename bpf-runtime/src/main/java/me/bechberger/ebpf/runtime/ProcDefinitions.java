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
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
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
 * Generated class for BPF runtime types that start with proc
 */
@java.lang.SuppressWarnings("unused")
public final class ProcDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__proc_create($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static Ptr<proc_dir_entry> __proc_create(Ptr<Ptr<proc_dir_entry>> parent, String name,
      @Unsigned @OriginalName("umode_t") short mode, @Unsigned @OriginalName("nlink_t") int nlink) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __proc_set_tty(Ptr<tty_struct> tty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int _proc_do_string(String data, int maxlen, int write, String buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_proc_mkdir((const u8*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<proc_dir_entry> _proc_mkdir(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent, Ptr<?> data,
      boolean force_lookup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> proc_alloc_inode(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_alloc_inum(Ptr<java.lang. @Unsigned Integer> inum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_allowed_congestion_control((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_allowed_congestion_control(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_apparmor_attr_dir_iterate(Ptr<file> filp, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_apparmor_attr_dir_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_archtype_show(Ptr<seq_file> file, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_attr_dir_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_attr_dir_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_available_path_managers((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_available_path_managers(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_available_schedulers((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_available_schedulers(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_blackhole_detect_timeout((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_blackhole_detect_timeout(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_boot_config_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long proc_bus_pci_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long proc_bus_pci_lseek(Ptr<file> file,
      @OriginalName("loff_t") long off, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_bus_pci_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_bus_pci_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_bus_pci_read(Ptr<file> file, String buf,
      @Unsigned long nbytes, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_bus_pci_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_bus_pci_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_bus_pci_write(Ptr<file> file, String buf,
      @Unsigned long nbytes, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_caches_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_cap_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_cap_handler(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_cgroup_show(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_cgroupstats_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_clear_tty(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_cmdline_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_comm_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_conninfo_ex(Ptr<usb_dev_state> ps, Ptr<?> arg, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_consoles_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_coredump_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_coredump_filter_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_coredump_filter_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_coredump_filter_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_cpuinfo_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create((const u8*)$arg1, $arg2, $arg3, (const struct proc_ops*)$arg4)")
  public static Ptr<proc_dir_entry> proc_create(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent,
      Ptr<proc_ops> proc_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_data((const u8*)$arg1, $arg2, $arg3, (const struct proc_ops*)$arg4, $arg5)")
  public static Ptr<proc_dir_entry> proc_create_data(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent,
      Ptr<proc_ops> proc_ops, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_mount_point((const u8*)$arg1)")
  public static Ptr<proc_dir_entry> proc_create_mount_point(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_net_data((const u8*)$arg1, $arg2, $arg3, (const struct seq_operations*)$arg4, $arg5, $arg6)")
  public static Ptr<proc_dir_entry> proc_create_net_data(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent,
      Ptr<seq_operations> ops, @Unsigned int state_size, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_net_data_write((const u8*)$arg1, $arg2, $arg3, (const struct seq_operations*)$arg4, $arg5, $arg6, $arg7)")
  public static Ptr<proc_dir_entry> proc_create_net_data_write(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent,
      Ptr<seq_operations> ops, @OriginalName("proc_write_t") Ptr<?> write, @Unsigned int state_size,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_net_single((const u8*)$arg1, $arg2, $arg3, (int (*)(struct seq_file*, void*))$arg4, $arg5)")
  public static Ptr<proc_dir_entry> proc_create_net_single(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent, Ptr<?> show,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_net_single_write((const u8*)$arg1, $arg2, $arg3, (int (*)(struct seq_file*, void*))$arg4, $arg5, $arg6)")
  public static Ptr<proc_dir_entry> proc_create_net_single_write(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent, Ptr<?> show,
      @OriginalName("proc_write_t") Ptr<?> write, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_reg((const u8*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<proc_dir_entry> proc_create_reg(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<Ptr<proc_dir_entry>> parent, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_seq_private((const u8*)$arg1, $arg2, $arg3, (const struct seq_operations*)$arg4, $arg5, $arg6)")
  public static Ptr<proc_dir_entry> proc_create_seq_private(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent,
      Ptr<seq_operations> ops, @Unsigned int state_size, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_create_single_data((const u8*)$arg1, $arg2, $arg3, (int (*)(struct seq_file*, void*))$arg4, $arg5)")
  public static Ptr<proc_dir_entry> proc_create_single_data(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent, Ptr<?> show,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_cwd_link(Ptr<dentry> dentry, Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_devices_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long proc_dir_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_disconnect_claim(Ptr<usb_dev_state> ps, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_dma_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_dma_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_cad_pid((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_cad_pid(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_dev_weight((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_dev_weight(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_large_bitmap((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_large_bitmap(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_rointvec((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_rointvec(Ptr<ctl_table> table, int write, Ptr<?> buf,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_rss_key((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_rss_key(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_static_key((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_static_key(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_do_submiturb(Ptr<usb_dev_state> ps, Ptr<usbdevfs_urb> uurb,
      Ptr<usbdevfs_iso_packet_desc> iso_frame_desc, Ptr<?> arg,
      @OriginalName("sigval_t") sigval userurb_sigval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_uts_string((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_uts_string(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_do_uuid((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_do_uuid(Ptr<ctl_table> table, int write, Ptr<?> buf,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dobool((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dobool(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dohung_task_timeout_secs((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dohung_task_timeout_secs(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_jiffies((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_jiffies(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax_bpf_enable((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax_bpf_enable(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax_bpf_restricted((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax_bpf_restricted(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax_coredump((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax_coredump(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax_sysadmin((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax_sysadmin(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_minmax_warn_RT_change((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_minmax_warn_RT_change(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_ms_jiffies((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_ms_jiffies(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_ms_jiffies_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_ms_jiffies_minmax(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dointvec_userhz_jiffies((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dointvec_userhz_jiffies(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dolongvec_minmax_bpf_restricted((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dolongvec_minmax_bpf_restricted(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dopipe_max_size((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dopipe_max_size(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dostring((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dostring(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dostring_coredump((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dostring_coredump(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_dou8vec_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_dou8vec_minmax(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_douintvec((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_douintvec(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_douintvec_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_douintvec_minmax(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_doulongvec_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_doulongvec_minmax(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_doulongvec_ms_jiffies_minmax((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_doulongvec_ms_jiffies_minmax(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_entry_rundown(Ptr<proc_dir_entry> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_evict_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_exe_link(Ptr<dentry> dentry, Ptr<path> exe_path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_exec_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_execdomains_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_exit_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fd_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_fd_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fd_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_fd_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fd_iterate(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fd_link(Ptr<dentry> dentry, Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fd_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fdinfo_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_fdinfo_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fdinfo_iterate(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fdinfo_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fib_multipath_hash_fields((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_fib_multipath_hash_fields(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fib_multipath_hash_policy((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_fib_multipath_hash_policy(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fib_multipath_hash_seed((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_fib_multipath_hash_seed(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_filesystems_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_fill_cache($arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, (const void*)$arg7)")
  public static boolean proc_fill_cache(Ptr<file> file, Ptr<dir_context> ctx, String name,
      @Unsigned int len, Ptr<?> instantiate, Ptr<task_struct> task, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_fill_super(Ptr<super_block> s, Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_flush_pid(Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_fork_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_free_inode(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_free_inum(@Unsigned int inum) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_fs_context_free(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_genhd_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> proc_get_inode(Ptr<super_block> sb, Ptr<proc_dir_entry> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_get_link($arg1, $arg2, $arg3))")
  public static String proc_get_link(Ptr<dentry> dentry, Ptr<inode> inode, Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_get_parent_data((const struct inode*)$arg1)")
  public static Ptr<?> proc_get_parent_data(Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_get_tree(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_getdriver(Ptr<usb_dev_state> ps, Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_gid_map_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_gid_map_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_gid_map_write(Ptr<file> file, String buf,
      @Unsigned long size, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_hubbed_show(Ptr<seq_file> file, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_hubless_show(Ptr<seq_file> file, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_id_connector(Ptr<task_struct> task, int which_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_id_map_open($arg1, $arg2, (const struct seq_operations*)$arg3)")
  public static int proc_id_map_open(Ptr<inode> inode, Ptr<file> file,
      Ptr<seq_operations> seq_ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_id_map_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_init_fs_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_init_kmemcache() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_interrupts_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_invalidate_siblings_dcache(Ptr<hlist_head> inodes,
      Ptr<@OriginalName("spinlock_t") spinlock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_ioctl(Ptr<usb_dev_state> ps, Ptr<usbdevfs_ioctl> ctl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_ipc_auto_msgmni((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_ipc_auto_msgmni(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_ipc_dointvec_minmax_orphans((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_ipc_dointvec_minmax_orphans(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_ipc_sem_dointvec((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_ipc_sem_dointvec(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_kcore_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> proc_key_users_next(Ptr<seq_file> p, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> _pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_key_users_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> proc_key_users_start(Ptr<seq_file> p,
      Ptr<java.lang. @OriginalName("loff_t") Long> _pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_key_users_stop(Ptr<seq_file> p, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> proc_keys_next(Ptr<seq_file> p, Ptr<?> v,
      Ptr<java.lang. @OriginalName("loff_t") Long> _pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_keys_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> proc_keys_start(Ptr<seq_file> p,
      Ptr<java.lang. @OriginalName("loff_t") Long> _pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_keys_stop(Ptr<seq_file> p, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_kill_sb(Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_kmsg_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_kprobes_optimization_handler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_kprobes_optimization_handler(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> length,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_loadavg_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_locks_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_loginuid_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_loginuid_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_loginuid_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_lookup(Ptr<inode> dir, Ptr<dentry> dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_lookup_de(Ptr<inode> dir, Ptr<dentry> dentry,
      Ptr<proc_dir_entry> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_lookupfd(Ptr<inode> dir, Ptr<dentry> dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_lookupfdinfo(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_map_files_get_link($arg1, $arg2, $arg3))")
  public static String proc_map_files_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_map_files_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_map_files_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_map_files_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_map_files_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_map_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_match((const u8*)$arg1, $arg2, $arg3)")
  public static int proc_match(String name, Ptr<proc_dir_entry> de, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<mm_struct> proc_mem_open(Ptr<inode> inode, @Unsigned int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_meminfo_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_misc_d_delete((const struct dentry*)$arg1)")
  public static int proc_misc_d_delete(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_misc_d_revalidate($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int proc_misc_d_revalidate(Ptr<inode> dir, Ptr<qstr> name, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_mkdir((const u8*)$arg1, $arg2)")
  public static Ptr<proc_dir_entry> proc_mkdir(String name, Ptr<proc_dir_entry> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_mkdir_data((const u8*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<proc_dir_entry> proc_mkdir_data(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_mkdir_mode((const u8*)$arg1, $arg2, $arg3)")
  public static Ptr<proc_dir_entry> proc_mkdir_mode(String name,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<proc_dir_entry> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_modules_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_net_d_revalidate($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int proc_net_d_revalidate(Ptr<inode> dir, Ptr<qstr> name, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_net_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_net_ns_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_net_ns_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_nmi_watchdog((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_nmi_watchdog(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_notify_change(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> iattr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_nr_dentry((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_nr_dentry(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_nr_files((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_nr_files(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_nr_inodes((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_nr_inodes(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_ns_dir_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_ns_dir_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_ns_file((const struct file*)$arg1)")
  public static boolean proc_ns_file(Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_ns_get_link($arg1, $arg2, $arg3))")
  public static String proc_ns_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_ns_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_ns_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_ns_readlink(Ptr<dentry> dentry, String buffer, int buflen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_oom_score(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_page_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_parse_param(Ptr<fs_context> fc, Ptr<fs_parameter> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_path_manager((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_path_manager(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_arch_status(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_attr_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_pid_attr_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pid_attr_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_pid_attr_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_pid_cmdline_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_pid_evict_inode(Ptr<proc_inode> ei) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_pid_get_link($arg1, $arg2, $arg3))")
  public static String proc_pid_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pid_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_pid_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_ksm_merging_pages(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_ksm_stat(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_limits(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_pid_lookup(Ptr<dentry> dentry, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> proc_pid_make_base_inode(Ptr<super_block> sb, Ptr<task_struct> task,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<inode> proc_pid_make_inode(Ptr<super_block> sb, Ptr<task_struct> task,
      @Unsigned @OriginalName("umode_t") short mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_patch_state(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_personality(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_readlink(Ptr<dentry> dentry, String buffer, int buflen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_schedstat(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_stack(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_statm(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_status(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_syscall(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_pid_wchan(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pident_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_pident_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pident_lookup($arg1, $arg2, (const struct pid_entry*)$arg3, (const struct pid_entry*)$arg4)")
  public static Ptr<dentry> proc_pident_lookup(Ptr<inode> dir, Ptr<dentry> dentry, Ptr<pid_entry> p,
      Ptr<pid_entry> end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pident_readdir($arg1, $arg2, (const struct pid_entry*)$arg3, $arg4)")
  public static int proc_pident_readdir(Ptr<file> file, Ptr<dir_context> ctx, Ptr<pid_entry> ents,
      @Unsigned int nents) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_pm_type((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_pm_type(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_print_scsidevice(Ptr<device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_projid_map_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_projid_map_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_projid_map_write(Ptr<file> file, String buf,
      @Unsigned long size, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_ptrace_connector(Ptr<task_struct> task, int ptrace_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_put_link(Ptr<?> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_put_long(Ptr<Ptr<?>> buf, Ptr<java.lang. @Unsigned Long> size,
      @Unsigned long val, boolean neg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_readdir_de(Ptr<file> file, Ptr<dir_context> ctx, Ptr<proc_dir_entry> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_readfd_common(Ptr<file> file, Ptr<dir_context> ctx, Ptr<?> instantiate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_readfd_count(Ptr<inode> inode,
      Ptr<java.lang. @OriginalName("loff_t") Long> count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_reconfigure(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long proc_reg_compat_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long proc_reg_get_unmapped_area(Ptr<file> file, @Unsigned long orig_addr,
      @Unsigned long len, @Unsigned long pgoff, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long proc_reg_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_reg_mmap(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_reg_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int proc_reg_poll(Ptr<file> file,
      Ptr<poll_table_struct> pts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_reg_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_reg_read_iter(Ptr<kiocb> iocb,
      Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_reg_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long proc_reg_unlocked_ioctl(Ptr<file> file, @Unsigned int cmd,
      @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_reg_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_reg_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<proc_dir_entry> proc_register(Ptr<proc_dir_entry> dir, Ptr<proc_dir_entry> dp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_remove(Ptr<proc_dir_entry> de) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_resctrl_show(Ptr<seq_file> s, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_root_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_root_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_root_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_root_link(Ptr<dentry> dentry, Ptr<path> path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_root_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_root_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_rt6_multipath_hash_fields((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_rt6_multipath_hash_fields(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_rt6_multipath_hash_policy((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_rt6_multipath_hash_policy(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sched_autogroup_set_nice(Ptr<task_struct> p, int nice) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sched_autogroup_show_task(Ptr<task_struct> p, Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sched_set_task(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sched_show_task(Ptr<task_struct> p, Ptr<pid_namespace> ns,
      Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_schedstat_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_scheduler((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_scheduler(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_scsi_devinfo_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_scsi_devinfo_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_scsi_devinfo_write(Ptr<file> file, String buf,
      @Unsigned long length, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_scsi_host_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_scsi_host_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_scsi_host_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_scsi_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_scsi_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_scsi_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_scsi_write(Ptr<file> file, String buf,
      @Unsigned long length, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_self_get_link($arg1, $arg2, $arg3))")
  public static String proc_self_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_self_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_seq_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_seq_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_sessionid_read(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_set_size(Ptr<proc_dir_entry> de, @OriginalName("loff_t") long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_set_user(Ptr<proc_dir_entry> de, kuid_t uid, kgid_t gid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setgroups_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setgroups_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setgroups_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_setgroups_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_setgroups_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setup_self(Ptr<super_block> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_setup_thread_self(Ptr<super_block> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_show_options(Ptr<seq_file> seq, Ptr<dentry> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sid_connector(Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_simple_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_simple_write(Ptr<file> f, String ubuf,
      @Unsigned long size, Ptr<java.lang. @OriginalName("loff_t") Long> _pos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_single_open(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_single_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_smack_attr_dir_iterate(Ptr<file> filp, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_smack_attr_dir_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_soft_watchdog((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_soft_watchdog(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_softirqs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_stat_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_symlink((const u8*)$arg1, $arg2, (const u8*)$arg3)")
  public static Ptr<proc_dir_entry> proc_symlink(String name, Ptr<proc_dir_entry> parent,
      String dest) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_sys_call_handler(Ptr<kiocb> iocb,
      Ptr<iov_iter> iter, int write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_sys_compare((const struct dentry*)$arg1, $arg2, (const u8*)$arg3, (const struct qstr*)$arg4)")
  public static int proc_sys_compare(Ptr<dentry> dentry, @Unsigned int len, String str,
      Ptr<qstr> name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_sys_delete((const struct dentry*)$arg1)")
  public static int proc_sys_delete(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sys_evict_inode(Ptr<inode> inode, Ptr<ctl_table_header> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_sys_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_sys_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sys_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_sys_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_sys_make_inode($arg1, $arg2, (const struct ctl_table*)$arg3)")
  public static Ptr<inode> proc_sys_make_inode(Ptr<super_block> sb, Ptr<ctl_table_header> head,
      Ptr<ctl_table> table) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sys_open(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sys_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int proc_sys_poll(Ptr<file> filp,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_sys_poll_notify(Ptr<ctl_table_poll> poll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_sys_read(Ptr<kiocb> iocb, Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sys_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_sys_revalidate($arg1, (const struct qstr*)$arg2, $arg3, $arg4)")
  public static int proc_sys_revalidate(Ptr<inode> dir, Ptr<qstr> name, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_sys_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long proc_sys_write(Ptr<kiocb> iocb, Ptr<iov_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_taint((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_taint(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_task_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_task_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_task_instantiate($arg1, $arg2, (const void*)$arg3)")
  public static Ptr<dentry> proc_task_instantiate(Ptr<dentry> dentry, Ptr<task_struct> task,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_task_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_task_name(Ptr<seq_file> m, Ptr<task_struct> p, boolean escape) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_task_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tcp_available_congestion_control((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tcp_available_congestion_control(Ptr<ctl_table> ctl, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tcp_available_ulp((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tcp_available_ulp(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tcp_congestion_control((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tcp_congestion_control(Ptr<ctl_table> ctl, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tcp_ehash_entries((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tcp_ehash_entries(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tcp_fastopen_key((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tcp_fastopen_key(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tfo_blackhole_detect_timeout((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_tfo_blackhole_detect_timeout(Ptr<ctl_table> table, int write,
      Ptr<?> buffer, Ptr<java.lang. @Unsigned Long> lenp,
      Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_tgid_base_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tgid_base_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tgid_io_accounting(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_tgid_net_getattr($arg1, (const struct path*)$arg2, $arg3, $arg4, $arg5)")
  public static int proc_tgid_net_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_tgid_net_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tgid_net_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tgid_stat(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)proc_thread_self_get_link($arg1, $arg2, $arg3))")
  public static String proc_thread_self_get_link(Ptr<dentry> dentry, Ptr<inode> inode,
      Ptr<delayed_call> done) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_thread_self_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dentry> proc_tid_base_lookup(Ptr<inode> dir, Ptr<dentry> dentry,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tid_base_readdir(Ptr<file> file, Ptr<dir_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tid_comm_permission(Ptr<mnt_idmap> idmap, Ptr<inode> inode, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tid_io_accounting(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_tid_stat(Ptr<seq_file> m, Ptr<pid_namespace> ns, Ptr<pid> pid,
      Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_timens_set_offset(Ptr<file> file, Ptr<task_struct> p,
      Ptr<proc_timens_offset> offsets, int noffsets) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_timens_show_offsets(Ptr<task_struct> p, Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_timers_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_tty_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_tty_register_driver(Ptr<tty_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_tty_unregister_driver(Ptr<tty_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_udp_hash_entries((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_udp_hash_entries(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_uid_map_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_uid_map_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long proc_uid_map_write(Ptr<file> file, String buf,
      @Unsigned long size, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_uptime_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_version_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_version_signature_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int proc_vmalloc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_watchdog((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_watchdog(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_watchdog_common($arg1, (const struct ctl_table*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int proc_watchdog_common(int which, Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_watchdog_cpumask((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_watchdog_cpumask(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("proc_watchdog_thresh((const struct ctl_table*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static int proc_watchdog_thresh(Ptr<ctl_table> table, int write, Ptr<?> buffer,
      Ptr<java.lang. @Unsigned Long> lenp, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void proc_watchdog_update(boolean thresh_changed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_ns_operations"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_ns_operations extends Struct {
    public String name;

    public String real_ns_name;

    public int type;

    public Ptr<?> get;

    public Ptr<?> put;

    public Ptr<?> install;

    public Ptr<?> owner;

    public Ptr<?> get_parent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_ops extends Struct {
    public @Unsigned int proc_flags;

    public Ptr<?> proc_open;

    public Ptr<?> proc_read;

    public Ptr<?> proc_read_iter;

    public Ptr<?> proc_write;

    public Ptr<?> proc_lseek;

    public Ptr<?> proc_release;

    public Ptr<?> proc_poll;

    public Ptr<?> proc_ioctl;

    public Ptr<?> proc_compat_ioctl;

    public Ptr<?> proc_mmap;

    public Ptr<?> proc_get_unmapped_area;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_cn_event"
  )
  public enum proc_cn_event implements Enum<proc_cn_event>, TypedEnum<proc_cn_event, java.lang. @Unsigned Integer> {
    /**
     * {@code PROC_EVENT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PROC_EVENT_NONE"
    )
    PROC_EVENT_NONE,

    /**
     * {@code PROC_EVENT_FORK = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PROC_EVENT_FORK"
    )
    PROC_EVENT_FORK,

    /**
     * {@code PROC_EVENT_EXEC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PROC_EVENT_EXEC"
    )
    PROC_EVENT_EXEC,

    /**
     * {@code PROC_EVENT_UID = 4}
     */
    @EnumMember(
        value = 4L,
        name = "PROC_EVENT_UID"
    )
    PROC_EVENT_UID,

    /**
     * {@code PROC_EVENT_GID = 64}
     */
    @EnumMember(
        value = 64L,
        name = "PROC_EVENT_GID"
    )
    PROC_EVENT_GID,

    /**
     * {@code PROC_EVENT_SID = 128}
     */
    @EnumMember(
        value = 128L,
        name = "PROC_EVENT_SID"
    )
    PROC_EVENT_SID,

    /**
     * {@code PROC_EVENT_PTRACE = 256}
     */
    @EnumMember(
        value = 256L,
        name = "PROC_EVENT_PTRACE"
    )
    PROC_EVENT_PTRACE,

    /**
     * {@code PROC_EVENT_COMM = 512}
     */
    @EnumMember(
        value = 512L,
        name = "PROC_EVENT_COMM"
    )
    PROC_EVENT_COMM,

    /**
     * {@code PROC_EVENT_NONZERO_EXIT = 536870912}
     */
    @EnumMember(
        value = 536870912L,
        name = "PROC_EVENT_NONZERO_EXIT"
    )
    PROC_EVENT_NONZERO_EXIT,

    /**
     * {@code PROC_EVENT_COREDUMP = 1073741824}
     */
    @EnumMember(
        value = 1073741824L,
        name = "PROC_EVENT_COREDUMP"
    )
    PROC_EVENT_COREDUMP,

    /**
     * {@code PROC_EVENT_EXIT = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "PROC_EVENT_EXIT"
    )
    PROC_EVENT_EXIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_timens_offset"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_timens_offset extends Struct {
    public int clockid;

    public timespec64 val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_mounts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_mounts extends Struct {
    public Ptr<mnt_namespace> ns;

    public path root;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_hidepid"
  )
  public enum proc_hidepid implements Enum<proc_hidepid>, TypedEnum<proc_hidepid, java.lang. @Unsigned Integer> {
    /**
     * {@code HIDEPID_OFF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "HIDEPID_OFF"
    )
    HIDEPID_OFF,

    /**
     * {@code HIDEPID_NO_ACCESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "HIDEPID_NO_ACCESS"
    )
    HIDEPID_NO_ACCESS,

    /**
     * {@code HIDEPID_INVISIBLE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HIDEPID_INVISIBLE"
    )
    HIDEPID_INVISIBLE,

    /**
     * {@code HIDEPID_NOT_PTRACEABLE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "HIDEPID_NOT_PTRACEABLE"
    )
    HIDEPID_NOT_PTRACEABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_pidonly"
  )
  public enum proc_pidonly implements Enum<proc_pidonly>, TypedEnum<proc_pidonly, java.lang. @Unsigned Integer> {
    /**
     * {@code PROC_PIDONLY_OFF = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PROC_PIDONLY_OFF"
    )
    PROC_PIDONLY_OFF,

    /**
     * {@code PROC_PIDONLY_ON = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PROC_PIDONLY_ON"
    )
    PROC_PIDONLY_ON
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_fs_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_fs_info extends Struct {
    public Ptr<pid_namespace> pid_ns;

    public Ptr<dentry> proc_self;

    public Ptr<dentry> proc_thread_self;

    public kgid_t pid_gid;

    public proc_hidepid hide_pid;

    public proc_pidonly pidonly;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_dir_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_dir_entry extends Struct {
    public atomic_t in_use;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public list_head pde_openers;

    public @OriginalName("spinlock_t") spinlock pde_unload_lock;

    public Ptr<completion> pde_unload_completion;

    public Ptr<inode_operations> proc_iops;

    @InlineUnion(22174)
    public Ptr<proc_ops> proc_ops;

    @InlineUnion(22174)
    public Ptr<file_operations> proc_dir_ops;

    @InlineUnion(22175)
    public Ptr<seq_operations> seq_ops;

    @InlineUnion(22175)
    public Ptr<?> single_show;

    public @OriginalName("proc_write_t") Ptr<?> write;

    public Ptr<?> data;

    public @Unsigned int state_size;

    public @Unsigned int low_ino;

    public @Unsigned @OriginalName("nlink_t") int nlink;

    public kuid_t uid;

    public kgid_t gid;

    public @OriginalName("loff_t") long size;

    public Ptr<proc_dir_entry> parent;

    public rb_root subdir;

    public rb_node subdir_node;

    public String name;

    public @Unsigned @OriginalName("umode_t") short mode;

    public char flags;

    public char namelen;

    public char @Size(0) [] inline_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union proc_op"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_op extends Union {
    public Ptr<?> proc_get_link;

    public Ptr<?> proc_show;

    public int lsmid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_inode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_inode extends Struct {
    public Ptr<pid> pid;

    public @Unsigned int fd;

    public proc_op op;

    public Ptr<proc_dir_entry> pde;

    public Ptr<ctl_table_header> sysctl;

    public Ptr<ctl_table> sysctl_entry;

    public hlist_node sibling_inodes;

    public Ptr<proc_ns_operations> ns_ops;

    public inode vfs_inode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_fs_opts"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_fs_opts extends Struct {
    public int flag;

    public String str;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_maps_private"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_maps_private extends Struct {
    public Ptr<inode> inode;

    public Ptr<task_struct> task;

    public Ptr<mm_struct> mm;

    public vma_iterator iter;

    public @OriginalName("loff_t") long last_pos;

    public boolean mmap_locked;

    public Ptr<vm_area_struct> locked_vma;

    public Ptr<mempolicy> task_mempolicy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_fs_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_fs_context extends Struct {
    public Ptr<pid_namespace> pid_ns;

    public @Unsigned int mask;

    public proc_hidepid hidepid;

    public int gid;

    public proc_pidonly pidonly;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_param"
  )
  public enum proc_param implements Enum<proc_param>, TypedEnum<proc_param, java.lang. @Unsigned Integer> {
    /**
     * {@code Opt_gid = 0}
     */
    @EnumMember(
        value = 0L,
        name = "Opt_gid"
    )
    Opt_gid,

    /**
     * {@code Opt_hidepid = 1}
     */
    @EnumMember(
        value = 1L,
        name = "Opt_hidepid"
    )
    Opt_hidepid,

    /**
     * {@code Opt_subset = 2}
     */
    @EnumMember(
        value = 2L,
        name = "Opt_subset"
    )
    Opt_subset
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_mem_force"
  )
  public enum proc_mem_force implements Enum<proc_mem_force>, TypedEnum<proc_mem_force, java.lang. @Unsigned Integer> {
    /**
     * {@code PROC_MEM_FORCE_ALWAYS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PROC_MEM_FORCE_ALWAYS"
    )
    PROC_MEM_FORCE_ALWAYS,

    /**
     * {@code PROC_MEM_FORCE_PTRACE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PROC_MEM_FORCE_PTRACE"
    )
    PROC_MEM_FORCE_PTRACE,

    /**
     * {@code PROC_MEM_FORCE_NEVER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PROC_MEM_FORCE_NEVER"
    )
    PROC_MEM_FORCE_NEVER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum proc_cn_mcast_op"
  )
  public enum proc_cn_mcast_op implements Enum<proc_cn_mcast_op>, TypedEnum<proc_cn_mcast_op, java.lang. @Unsigned Integer> {
    /**
     * {@code PROC_CN_MCAST_LISTEN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PROC_CN_MCAST_LISTEN"
    )
    PROC_CN_MCAST_LISTEN,

    /**
     * {@code PROC_CN_MCAST_IGNORE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PROC_CN_MCAST_IGNORE"
    )
    PROC_CN_MCAST_IGNORE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_input"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_input extends Struct {
    public proc_cn_mcast_op mcast_op;

    public proc_cn_event event_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct proc_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class proc_event extends Struct {
    public proc_cn_event what;

    public @Unsigned int cpu;

    public @Unsigned long timestamp_ns;

    public event_data_of_proc_event event_data;
  }
}
