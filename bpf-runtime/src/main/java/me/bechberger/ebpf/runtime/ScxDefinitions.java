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
 * Generated class for BPF runtime types that start with scx
 */
@java.lang.SuppressWarnings("unused")
public final class ScxDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __scx_update_idle(Ptr<rq> rq, boolean idle, boolean do_notify) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<scx_sched> scx_alloc_and_add_sched(Ptr<sched_ext_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_allow_ttwu_queue((const struct task_struct*)$arg1)")
  public static boolean scx_allow_ttwu_queue(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_enable_seq_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_events_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_hotplug_seq_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_nr_rejected_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_ops_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_state_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long scx_attr_switch_all_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> ka, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_bpf_cpu_node(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<rq> scx_bpf_cpu_rq(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_cpuperf_cap(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_cpuperf_cur(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_cpuperf_set(int cpu, @Unsigned int perf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_bpf_create_dsq(@Unsigned long dsq_id, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_destroy_dsq(@Unsigned long dsq_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dispatch_cancel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_dispatch_nr_slots() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dsq_insert(Ptr<task_struct> p, @Unsigned long dsq_id,
      @Unsigned long slice, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dsq_insert_vtime(Ptr<task_struct> p, @Unsigned long dsq_id,
      @Unsigned long slice, @Unsigned long vtime, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_bpf_dsq_move(Ptr<bpf_iter_scx_dsq> it__iter, Ptr<task_struct> p,
      @Unsigned long dsq_id, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dsq_move_set_slice(Ptr<bpf_iter_scx_dsq> it__iter,
      @Unsigned long slice) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dsq_move_set_vtime(Ptr<bpf_iter_scx_dsq> it__iter,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_bpf_dsq_move_to_local(@Unsigned long dsq_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_bpf_dsq_move_vtime(Ptr<bpf_iter_scx_dsq> it__iter, Ptr<task_struct> p,
      @Unsigned long dsq_id, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_bpf_dsq_nr_queued(@Unsigned long dsq_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_dump_bstr(String fmt, Ptr<java.lang. @Unsigned Long> data,
      @Unsigned int data__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_error_bstr(String fmt, Ptr<java.lang. @Unsigned Long> data,
      @Unsigned int data__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_events(Ptr<scx_event_stats> events, @Unsigned long events__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_exit_bstr(long exit_code, String fmt,
      Ptr<java.lang. @Unsigned Long> data, @Unsigned int data__sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_idle_cpumask())")
  public static Ptr<cpumask> scx_bpf_get_idle_cpumask() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_idle_cpumask_node($arg1))")
  public static Ptr<cpumask> scx_bpf_get_idle_cpumask_node(int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_idle_smtmask())")
  public static Ptr<cpumask> scx_bpf_get_idle_smtmask() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_idle_smtmask_node($arg1))")
  public static Ptr<cpumask> scx_bpf_get_idle_smtmask_node(int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_online_cpumask())")
  public static Ptr<cpumask> scx_bpf_get_online_cpumask() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct cpumask*)scx_bpf_get_possible_cpumask())")
  public static Ptr<cpumask> scx_bpf_get_possible_cpumask() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bpf_kick_cpu(int cpu, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long scx_bpf_now() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_nr_cpu_ids() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_nr_node_ids() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_pick_any_cpu((const struct cpumask*)$arg1, $arg2)")
  public static int scx_bpf_pick_any_cpu(Ptr<cpumask> cpus_allowed, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_pick_any_cpu_node((const struct cpumask*)$arg1, $arg2, $arg3)")
  public static int scx_bpf_pick_any_cpu_node(Ptr<cpumask> cpus_allowed, int node,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_pick_idle_cpu((const struct cpumask*)$arg1, $arg2)")
  public static int scx_bpf_pick_idle_cpu(Ptr<cpumask> cpus_allowed, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_pick_idle_cpu_node((const struct cpumask*)$arg1, $arg2, $arg3)")
  public static int scx_bpf_pick_idle_cpu_node(Ptr<cpumask> cpus_allowed, int node,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_put_cpumask((const struct cpumask*)$arg1)")
  public static void scx_bpf_put_cpumask(Ptr<cpumask> cpumask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_put_idle_cpumask((const struct cpumask*)$arg1)")
  public static void scx_bpf_put_idle_cpumask(Ptr<cpumask> idle_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int scx_bpf_reenqueue_local() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_select_cpu_and($arg1, $arg2, $arg3, (const struct cpumask*)$arg4, $arg5)")
  public static int scx_bpf_select_cpu_and(Ptr<task_struct> p, int prev_cpu,
      @Unsigned long wake_flags, Ptr<cpumask> cpus_allowed, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_bpf_select_cpu_dfl(Ptr<task_struct> p, int prev_cpu,
      @Unsigned long wake_flags, Ptr<java.lang. @OriginalName("bool") Boolean> is_idle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<cgroup> scx_bpf_task_cgroup(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_task_cpu((const struct task_struct*)$arg1)")
  public static int scx_bpf_task_cpu(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_bpf_task_running((const struct task_struct*)$arg1)")
  public static boolean scx_bpf_task_running(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_bpf_test_and_clear_cpu_idle(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_breather(Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_bypass(boolean bypass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_can_stop_tick(Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_cancel_fork(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_cgroup_can_attach(Ptr<cgroup_taskset> tset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_cgroup_cancel_attach(Ptr<cgroup_taskset> tset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_cgroup_exit(Ptr<scx_sched> sch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_cgroup_finish_attach() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_cgroup_init(Ptr<scx_sched> sch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_cgroup_move_task(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_check_setscheduler(Ptr<task_struct> p, int policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_disable_task(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_disable_workfn(Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_dsq_insert_commit(Ptr<task_struct> p, @Unsigned long dsq_id,
      @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_dsq_move(Ptr<bpf_iter_scx_dsq_kern> kit, Ptr<task_struct> p,
      @Unsigned long dsq_id, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_dump_state(Ptr<scx_exit_info> ei, @Unsigned long dump_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_dump_task(Ptr<seq_buf> s, Ptr<scx_dump_ctx> dctx, Ptr<task_struct> p,
      char marker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_enable(Ptr<sched_ext_ops> ops, Ptr<bpf_link> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_enable_task(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_error_irq_workfn(Ptr<irq_work> irq_work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_exit($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5_)")
  public static void scx_exit(Ptr<scx_sched> sch, scx_exit_kind kind, long exit_code, String fmt,
      java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_exit_task(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_fork(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_group_set_bandwidth(Ptr<task_group> tg, @Unsigned long period_us,
      @Unsigned long quota_us, @Unsigned long burst_us) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_group_set_idle(Ptr<task_group> tg, boolean idle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_group_set_weight(Ptr<task_group> tg, @Unsigned long weight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_idle_disable() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_idle_enable(Ptr<sched_ext_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_idle_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_idle_init_masks() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_idle_test_and_clear_cpu(int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_idle_update_selcpu_topology(Ptr<sched_ext_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_init_task(Ptr<task_struct> p, Ptr<task_group> tg, boolean fork) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_kf_exit($arg1, $arg2, (const u8*)$arg3, $arg4_)")
  public static void scx_kf_exit(scx_exit_kind kind, long exit_code, String fmt,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_kobj_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_pm_handler(Ptr<notifier_block> nb, @Unsigned long event, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_post_fork(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_pre_fork(Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_prio_less((const struct task_struct*)$arg1, (const struct task_struct*)$arg2, $arg3)")
  public static boolean scx_prio_less(Ptr<task_struct> a, Ptr<task_struct> b, boolean in_fi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean scx_rcu_cpu_stall() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_read_events(Ptr<scx_sched> sch, Ptr<scx_event_stats> events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_rq_activate(Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_rq_deactivate(Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_sched_free_rcu_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_select_cpu_dfl($arg1, $arg2, $arg3, (const struct cpumask*)$arg4, $arg5)")
  public static int scx_select_cpu_dfl(Ptr<task_struct> p, int prev_cpu, @Unsigned long wake_flags,
      Ptr<cpumask> cpus_allowed, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_set_task_state(Ptr<task_struct> p, scx_task_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_softlockup(@Unsigned int dur_s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<task_struct> scx_task_iter_next_locked(Ptr<scx_task_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_task_iter_stop(Ptr<scx_task_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_tg_init(Ptr<task_group> tg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_tg_offline(Ptr<task_group> tg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int scx_tg_online(Ptr<task_group> tg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_tick(Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_uevent((const struct kobject*)$arg1, $arg2)")
  public static int scx_uevent(Ptr<kobject> kobj, Ptr<kobj_uevent_env> env) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("scx_vexit($arg1, $arg2, $arg3, (const u8*)$arg4, $arg5)")
  public static void scx_vexit(Ptr<scx_sched> sch, scx_exit_kind kind, long exit_code, String fmt,
      Ptr<__va_list_tag> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void scx_watchdog_workfn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * @deprecated Renamed to {@link #scx_bpf_dsq_insert()} in kernel 6.12. Renamed in sched_ext API cleanup (kernel 6.12)
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  @java.lang.Deprecated
  public static void scx_bpf_dispatch(Ptr<task_struct> p, @Unsigned long dsq_id,
      @Unsigned long slice, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * @deprecated Renamed to {@link #scx_bpf_dsq_move()} in kernel 6.12. Renamed in sched_ext API cleanup (kernel 6.12)
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  @java.lang.Deprecated
  public static boolean scx_bpf_dispatch_from_dsq(Ptr<bpf_iter_scx_dsq> it__iter,
      Ptr<task_struct> p, @Unsigned long dsq_id, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  /**
   * @deprecated Renamed to {@link #scx_bpf_dsq_insert_vtime()} in kernel 6.12. Renamed in sched_ext API cleanup (kernel 6.12)
   */
  @NotUsableInJava
  @BuiltinBPFFunction
  @java.lang.Deprecated
  public static void scx_bpf_dispatch_vtime(Ptr<task_struct> p, @Unsigned long dsq_id,
      @Unsigned long slice, @Unsigned long vtime, @Unsigned long enq_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dispatch_q"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dispatch_q extends Struct {
    public @OriginalName("raw_spinlock_t") raw_spinlock lock;

    public list_head list;

    public rb_root priq;

    public @Unsigned int nr;

    public @Unsigned int seq;

    public @Unsigned long id;

    public rhash_head hash_node;

    public llist_node free_node;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dsq_list_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dsq_list_node extends Struct {
    public list_head node;

    public @Unsigned int flags;

    public @Unsigned int priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_public_consts"
  )
  public enum scx_public_consts implements Enum<scx_public_consts>, TypedEnum<scx_public_consts, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_OPS_NAME_LEN = 128}
     */
    @EnumMember(
        value = 128L,
        name = "SCX_OPS_NAME_LEN"
    )
    SCX_OPS_NAME_LEN,

    /**
     * {@code SCX_SLICE_DFL = 20000000}
     */
    @EnumMember(
        value = 20000000L,
        name = "SCX_SLICE_DFL"
    )
    SCX_SLICE_DFL,

    /**
     * {@code SCX_SLICE_INF = -1}
     */
    @EnumMember(
        value = -1L,
        name = "SCX_SLICE_INF"
    )
    SCX_SLICE_INF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_dsq_id_flags"
  )
  public enum scx_dsq_id_flags implements Enum<scx_dsq_id_flags>, TypedEnum<scx_dsq_id_flags, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_DSQ_FLAG_BUILTIN = -9223372036854775808}
     */
    @EnumMember(
        value = -9223372036854775808L,
        name = "SCX_DSQ_FLAG_BUILTIN"
    )
    SCX_DSQ_FLAG_BUILTIN,

    /**
     * {@code SCX_DSQ_FLAG_LOCAL_ON = 4611686018427387904}
     */
    @EnumMember(
        value = 4611686018427387904L,
        name = "SCX_DSQ_FLAG_LOCAL_ON"
    )
    SCX_DSQ_FLAG_LOCAL_ON,

    /**
     * {@code SCX_DSQ_INVALID = -9223372036854775808}
     */
    @EnumMember(
        value = -9223372036854775808L,
        name = "SCX_DSQ_INVALID"
    )
    SCX_DSQ_INVALID,

    /**
     * {@code SCX_DSQ_GLOBAL = -9223372036854775807}
     */
    @EnumMember(
        value = -9223372036854775807L,
        name = "SCX_DSQ_GLOBAL"
    )
    SCX_DSQ_GLOBAL,

    /**
     * {@code SCX_DSQ_LOCAL = -9223372036854775806}
     */
    @EnumMember(
        value = -9223372036854775806L,
        name = "SCX_DSQ_LOCAL"
    )
    SCX_DSQ_LOCAL,

    /**
     * {@code SCX_DSQ_LOCAL_ON = -4611686018427387904}
     */
    @EnumMember(
        value = -4611686018427387904L,
        name = "SCX_DSQ_LOCAL_ON"
    )
    SCX_DSQ_LOCAL_ON,

    /**
     * {@code SCX_DSQ_LOCAL_CPU_MASK = 4294967295}
     */
    @EnumMember(
        value = 4294967295L,
        name = "SCX_DSQ_LOCAL_CPU_MASK"
    )
    SCX_DSQ_LOCAL_CPU_MASK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_task_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_task_group extends Struct {
    public @Unsigned int flags;

    public @Unsigned int weight;

    public @Unsigned long bw_period_us;

    public @Unsigned long bw_quota_us;

    public @Unsigned long bw_burst_us;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_rq_flags"
  )
  public enum scx_rq_flags implements Enum<scx_rq_flags>, TypedEnum<scx_rq_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_RQ_ONLINE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_RQ_ONLINE"
    )
    SCX_RQ_ONLINE,

    /**
     * {@code SCX_RQ_CAN_STOP_TICK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_RQ_CAN_STOP_TICK"
    )
    SCX_RQ_CAN_STOP_TICK,

    /**
     * {@code SCX_RQ_BAL_PENDING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_RQ_BAL_PENDING"
    )
    SCX_RQ_BAL_PENDING,

    /**
     * {@code SCX_RQ_BAL_KEEP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_RQ_BAL_KEEP"
    )
    SCX_RQ_BAL_KEEP,

    /**
     * {@code SCX_RQ_BYPASSING = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCX_RQ_BYPASSING"
    )
    SCX_RQ_BYPASSING,

    /**
     * {@code SCX_RQ_CLK_VALID = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_RQ_CLK_VALID"
    )
    SCX_RQ_CLK_VALID,

    /**
     * {@code SCX_RQ_BAL_CB_PENDING = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SCX_RQ_BAL_CB_PENDING"
    )
    SCX_RQ_BAL_CB_PENDING,

    /**
     * {@code SCX_RQ_IN_WAKEUP = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "SCX_RQ_IN_WAKEUP"
    )
    SCX_RQ_IN_WAKEUP,

    /**
     * {@code SCX_RQ_IN_BALANCE = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "SCX_RQ_IN_BALANCE"
    )
    SCX_RQ_IN_BALANCE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_rq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_rq extends Struct {
    public scx_dispatch_q local_dsq;

    public list_head runnable_list;

    public list_head ddsp_deferred_locals;

    public @Unsigned long ops_qseq;

    public @Unsigned long extra_enq_flags;

    public @Unsigned int nr_running;

    public @Unsigned int cpuperf_target;

    public boolean cpu_released;

    public @Unsigned int flags;

    public @Unsigned long clock;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpus_to_kick;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpus_to_kick_if_idle;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpus_to_preempt;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpus_to_wait;

    public @Unsigned long pnt_seq;

    public balance_callback deferred_bal_cb;

    public irq_work deferred_irq_work;

    public irq_work kick_cpus_irq_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_ent_flags"
  )
  public enum scx_ent_flags implements Enum<scx_ent_flags>, TypedEnum<scx_ent_flags, java.lang.Integer> {
    /**
     * {@code SCX_TASK_QUEUED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_TASK_QUEUED"
    )
    SCX_TASK_QUEUED,

    /**
     * {@code SCX_TASK_RESET_RUNNABLE_AT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_TASK_RESET_RUNNABLE_AT"
    )
    SCX_TASK_RESET_RUNNABLE_AT,

    /**
     * {@code SCX_TASK_DEQD_FOR_SLEEP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_TASK_DEQD_FOR_SLEEP"
    )
    SCX_TASK_DEQD_FOR_SLEEP,

    /**
     * {@code SCX_TASK_STATE_SHIFT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_TASK_STATE_SHIFT"
    )
    SCX_TASK_STATE_SHIFT,

    /**
     * {@code SCX_TASK_STATE_BITS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_TASK_STATE_BITS"
    )
    SCX_TASK_STATE_BITS,

    /**
     * {@code SCX_TASK_STATE_MASK = 768}
     */
    @EnumMember(
        value = 768L,
        name = "SCX_TASK_STATE_MASK"
    )
    SCX_TASK_STATE_MASK,

    /**
     * {@code SCX_TASK_CURSOR = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "SCX_TASK_CURSOR"
    )
    SCX_TASK_CURSOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_task_state"
  )
  public enum scx_task_state implements Enum<scx_task_state>, TypedEnum<scx_task_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_TASK_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_TASK_NONE"
    )
    SCX_TASK_NONE,

    /**
     * {@code SCX_TASK_INIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_TASK_INIT"
    )
    SCX_TASK_INIT,

    /**
     * {@code SCX_TASK_READY = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_TASK_READY"
    )
    SCX_TASK_READY,

    /**
     * {@code SCX_TASK_ENABLED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCX_TASK_ENABLED"
    )
    SCX_TASK_ENABLED,

    /**
     * {@code SCX_TASK_NR_STATES = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_TASK_NR_STATES"
    )
    SCX_TASK_NR_STATES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_ent_dsq_flags"
  )
  public enum scx_ent_dsq_flags implements Enum<scx_ent_dsq_flags>, TypedEnum<scx_ent_dsq_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_TASK_DSQ_ON_PRIQ = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_TASK_DSQ_ON_PRIQ"
    )
    SCX_TASK_DSQ_ON_PRIQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_kf_mask"
  )
  public enum scx_kf_mask implements Enum<scx_kf_mask>, TypedEnum<scx_kf_mask, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_KF_UNLOCKED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_KF_UNLOCKED"
    )
    SCX_KF_UNLOCKED,

    /**
     * {@code SCX_KF_CPU_RELEASE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_KF_CPU_RELEASE"
    )
    SCX_KF_CPU_RELEASE,

    /**
     * {@code SCX_KF_DISPATCH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_KF_DISPATCH"
    )
    SCX_KF_DISPATCH,

    /**
     * {@code SCX_KF_ENQUEUE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_KF_ENQUEUE"
    )
    SCX_KF_ENQUEUE,

    /**
     * {@code SCX_KF_SELECT_CPU = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_KF_SELECT_CPU"
    )
    SCX_KF_SELECT_CPU,

    /**
     * {@code SCX_KF_REST = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCX_KF_REST"
    )
    SCX_KF_REST,

    /**
     * {@code __SCX_KF_RQ_LOCKED = 31}
     */
    @EnumMember(
        value = 31L,
        name = "__SCX_KF_RQ_LOCKED"
    )
    __SCX_KF_RQ_LOCKED,

    /**
     * {@code __SCX_KF_TERMINAL = 28}
     */
    @EnumMember(
        value = 28L,
        name = "__SCX_KF_TERMINAL"
    )
    __SCX_KF_TERMINAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_dsq_lnode_flags"
  )
  public enum scx_dsq_lnode_flags implements Enum<scx_dsq_lnode_flags>, TypedEnum<scx_dsq_lnode_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_DSQ_LNODE_ITER_CURSOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_DSQ_LNODE_ITER_CURSOR"
    )
    SCX_DSQ_LNODE_ITER_CURSOR,

    /**
     * {@code __SCX_DSQ_LNODE_PRIV_SHIFT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "__SCX_DSQ_LNODE_PRIV_SHIFT"
    )
    __SCX_DSQ_LNODE_PRIV_SHIFT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_consts"
  )
  public enum scx_consts implements Enum<scx_consts>, TypedEnum<scx_consts, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_DSP_DFL_MAX_BATCH = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_DSP_DFL_MAX_BATCH"
    )
    SCX_DSP_DFL_MAX_BATCH,

    /**
     * {@code SCX_DSP_MAX_LOOPS = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_DSP_MAX_LOOPS"
    )
    SCX_DSP_MAX_LOOPS,

    /**
     * {@code SCX_WATCHDOG_MAX_TIMEOUT = 30000}
     */
    @EnumMember(
        value = 30000L,
        name = "SCX_WATCHDOG_MAX_TIMEOUT"
    )
    SCX_WATCHDOG_MAX_TIMEOUT,

    /**
     * {@code SCX_EXIT_BT_LEN = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SCX_EXIT_BT_LEN"
    )
    SCX_EXIT_BT_LEN,

    /**
     * {@code SCX_EXIT_MSG_LEN = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "SCX_EXIT_MSG_LEN"
    )
    SCX_EXIT_MSG_LEN,

    /**
     * {@code SCX_EXIT_DUMP_DFL_LEN = 32768}
     */
    @EnumMember(
        value = 32768L,
        name = "SCX_EXIT_DUMP_DFL_LEN"
    )
    SCX_EXIT_DUMP_DFL_LEN,

    /**
     * {@code SCX_CPUPERF_ONE = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "SCX_CPUPERF_ONE"
    )
    SCX_CPUPERF_ONE,

    /**
     * {@code SCX_TASK_ITER_BATCH = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_TASK_ITER_BATCH"
    )
    SCX_TASK_ITER_BATCH
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_exit_kind"
  )
  public enum scx_exit_kind implements Enum<scx_exit_kind>, TypedEnum<scx_exit_kind, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_EXIT_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_EXIT_NONE"
    )
    SCX_EXIT_NONE,

    /**
     * {@code SCX_EXIT_DONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_EXIT_DONE"
    )
    SCX_EXIT_DONE,

    /**
     * {@code SCX_EXIT_UNREG = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SCX_EXIT_UNREG"
    )
    SCX_EXIT_UNREG,

    /**
     * {@code SCX_EXIT_UNREG_BPF = 65}
     */
    @EnumMember(
        value = 65L,
        name = "SCX_EXIT_UNREG_BPF"
    )
    SCX_EXIT_UNREG_BPF,

    /**
     * {@code SCX_EXIT_UNREG_KERN = 66}
     */
    @EnumMember(
        value = 66L,
        name = "SCX_EXIT_UNREG_KERN"
    )
    SCX_EXIT_UNREG_KERN,

    /**
     * {@code SCX_EXIT_SYSRQ = 67}
     */
    @EnumMember(
        value = 67L,
        name = "SCX_EXIT_SYSRQ"
    )
    SCX_EXIT_SYSRQ,

    /**
     * {@code SCX_EXIT_ERROR = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "SCX_EXIT_ERROR"
    )
    SCX_EXIT_ERROR,

    /**
     * {@code SCX_EXIT_ERROR_BPF = 1025}
     */
    @EnumMember(
        value = 1025L,
        name = "SCX_EXIT_ERROR_BPF"
    )
    SCX_EXIT_ERROR_BPF,

    /**
     * {@code SCX_EXIT_ERROR_STALL = 1026}
     */
    @EnumMember(
        value = 1026L,
        name = "SCX_EXIT_ERROR_STALL"
    )
    SCX_EXIT_ERROR_STALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_exit_code"
  )
  public enum scx_exit_code implements Enum<scx_exit_code>, TypedEnum<scx_exit_code, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_ECODE_RSN_HOTPLUG = 4294967296}
     */
    @EnumMember(
        value = 4294967296L,
        name = "SCX_ECODE_RSN_HOTPLUG"
    )
    SCX_ECODE_RSN_HOTPLUG,

    /**
     * {@code SCX_ECODE_ACT_RESTART = 281474976710656}
     */
    @EnumMember(
        value = 281474976710656L,
        name = "SCX_ECODE_ACT_RESTART"
    )
    SCX_ECODE_ACT_RESTART
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_exit_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_exit_info extends Struct {
    public scx_exit_kind kind;

    public long exit_code;

    public String reason;

    public Ptr<java.lang. @Unsigned Long> bt;

    public @Unsigned int bt_len;

    public String msg;

    public String dump;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_ops_flags"
  )
  public enum scx_ops_flags implements Enum<scx_ops_flags>, TypedEnum<scx_ops_flags, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_OPS_KEEP_BUILTIN_IDLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_OPS_KEEP_BUILTIN_IDLE"
    )
    SCX_OPS_KEEP_BUILTIN_IDLE,

    /**
     * {@code SCX_OPS_ENQ_LAST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_OPS_ENQ_LAST"
    )
    SCX_OPS_ENQ_LAST,

    /**
     * {@code SCX_OPS_ENQ_EXITING = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_OPS_ENQ_EXITING"
    )
    SCX_OPS_ENQ_EXITING,

    /**
     * {@code SCX_OPS_SWITCH_PARTIAL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_OPS_SWITCH_PARTIAL"
    )
    SCX_OPS_SWITCH_PARTIAL,

    /**
     * {@code SCX_OPS_ENQ_MIGRATION_DISABLED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCX_OPS_ENQ_MIGRATION_DISABLED"
    )
    SCX_OPS_ENQ_MIGRATION_DISABLED,

    /**
     * {@code SCX_OPS_ALLOW_QUEUED_WAKEUP = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_OPS_ALLOW_QUEUED_WAKEUP"
    )
    SCX_OPS_ALLOW_QUEUED_WAKEUP,

    /**
     * {@code SCX_OPS_BUILTIN_IDLE_PER_NODE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "SCX_OPS_BUILTIN_IDLE_PER_NODE"
    )
    SCX_OPS_BUILTIN_IDLE_PER_NODE,

    /**
     * {@code SCX_OPS_HAS_CGROUP_WEIGHT = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "SCX_OPS_HAS_CGROUP_WEIGHT"
    )
    SCX_OPS_HAS_CGROUP_WEIGHT,

    /**
     * {@code SCX_OPS_ALL_FLAGS = 65663}
     */
    @EnumMember(
        value = 65663L,
        name = "SCX_OPS_ALL_FLAGS"
    )
    SCX_OPS_ALL_FLAGS,

    /**
     * {@code __SCX_OPS_INTERNAL_MASK = -72057594037927936}
     */
    @EnumMember(
        value = -72057594037927936L,
        name = "__SCX_OPS_INTERNAL_MASK"
    )
    __SCX_OPS_INTERNAL_MASK,

    /**
     * {@code SCX_OPS_HAS_CPU_PREEMPT = 72057594037927936}
     */
    @EnumMember(
        value = 72057594037927936L,
        name = "SCX_OPS_HAS_CPU_PREEMPT"
    )
    SCX_OPS_HAS_CPU_PREEMPT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_init_task_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_init_task_args extends Struct {
    public boolean fork;

    public Ptr<cgroup> cgroup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_exit_task_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_exit_task_args extends Struct {
    public boolean cancelled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_cgroup_init_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_cgroup_init_args extends Struct {
    public @Unsigned int weight;

    public @Unsigned long bw_period_us;

    public @Unsigned long bw_quota_us;

    public @Unsigned long bw_burst_us;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_cpu_preempt_reason"
  )
  public enum scx_cpu_preempt_reason implements Enum<scx_cpu_preempt_reason>, TypedEnum<scx_cpu_preempt_reason, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_CPU_PREEMPT_RT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_CPU_PREEMPT_RT"
    )
    SCX_CPU_PREEMPT_RT,

    /**
     * {@code SCX_CPU_PREEMPT_DL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_CPU_PREEMPT_DL"
    )
    SCX_CPU_PREEMPT_DL,

    /**
     * {@code SCX_CPU_PREEMPT_STOP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_CPU_PREEMPT_STOP"
    )
    SCX_CPU_PREEMPT_STOP,

    /**
     * {@code SCX_CPU_PREEMPT_UNKNOWN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCX_CPU_PREEMPT_UNKNOWN"
    )
    SCX_CPU_PREEMPT_UNKNOWN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_cpu_acquire_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_cpu_acquire_args extends Struct {
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_cpu_release_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_cpu_release_args extends Struct {
    public scx_cpu_preempt_reason reason;

    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dump_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dump_ctx extends Struct {
    public scx_exit_kind kind;

    public long exit_code;

    public String reason;

    public @Unsigned long at_ns;

    public @Unsigned long at_jiffies;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_opi"
  )
  public enum scx_opi implements Enum<scx_opi>, TypedEnum<scx_opi, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_OPI_BEGIN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_OPI_BEGIN"
    )
    SCX_OPI_BEGIN,

    /**
     * {@code SCX_OPI_NORMAL_BEGIN = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_OPI_NORMAL_BEGIN"
    )
    SCX_OPI_NORMAL_BEGIN,

    /**
     * {@code SCX_OPI_NORMAL_END = 30}
     */
    @EnumMember(
        value = 30L,
        name = "SCX_OPI_NORMAL_END"
    )
    SCX_OPI_NORMAL_END,

    /**
     * {@code SCX_OPI_CPU_HOTPLUG_BEGIN = 30}
     */
    @EnumMember(
        value = 30L,
        name = "SCX_OPI_CPU_HOTPLUG_BEGIN"
    )
    SCX_OPI_CPU_HOTPLUG_BEGIN,

    /**
     * {@code SCX_OPI_CPU_HOTPLUG_END = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_OPI_CPU_HOTPLUG_END"
    )
    SCX_OPI_CPU_HOTPLUG_END,

    /**
     * {@code SCX_OPI_END = 32}
     */
    @EnumMember(
        value = 32L,
        name = "SCX_OPI_END"
    )
    SCX_OPI_END
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_event_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_event_stats extends Struct {
    public long SCX_EV_SELECT_CPU_FALLBACK;

    public long SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE;

    public long SCX_EV_DISPATCH_KEEP_LAST;

    public long SCX_EV_ENQ_SKIP_EXITING;

    public long SCX_EV_ENQ_SKIP_MIGRATION_DISABLED;

    public long SCX_EV_REFILL_SLICE_DFL;

    public long SCX_EV_BYPASS_DURATION;

    public long SCX_EV_BYPASS_DISPATCH;

    public long SCX_EV_BYPASS_ACTIVATE;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_sched_pcpu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_sched_pcpu extends Struct {
    public scx_event_stats event_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_sched"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_sched extends Struct {
    public sched_ext_ops ops;

    public @Unsigned long @Size(1) [] has_op;

    public rhashtable dsq_hash;

    public Ptr<Ptr<scx_dispatch_q>> global_dsqs;

    public Ptr<scx_sched_pcpu> pcpu;

    public boolean warned_zero_slice;

    public atomic_t exit_kind;

    public Ptr<scx_exit_info> exit_info;

    public kobject kobj;

    public Ptr<kthread_worker> helper;

    public irq_work error_irq_work;

    public kthread_work disable_work;

    public rcu_work rcu_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_wake_flags"
  )
  public enum scx_wake_flags implements Enum<scx_wake_flags>, TypedEnum<scx_wake_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_WAKE_FORK = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_WAKE_FORK"
    )
    SCX_WAKE_FORK,

    /**
     * {@code SCX_WAKE_TTWU = 8}
     */
    @EnumMember(
        value = 8L,
        name = "SCX_WAKE_TTWU"
    )
    SCX_WAKE_TTWU,

    /**
     * {@code SCX_WAKE_SYNC = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCX_WAKE_SYNC"
    )
    SCX_WAKE_SYNC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_enq_flags"
  )
  public enum scx_enq_flags implements Enum<scx_enq_flags>, TypedEnum<scx_enq_flags, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_ENQ_WAKEUP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_ENQ_WAKEUP"
    )
    SCX_ENQ_WAKEUP,

    /**
     * {@code SCX_ENQ_HEAD = 16}
     */
    @EnumMember(
        value = 16L,
        name = "SCX_ENQ_HEAD"
    )
    SCX_ENQ_HEAD,

    /**
     * {@code SCX_ENQ_CPU_SELECTED = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "SCX_ENQ_CPU_SELECTED"
    )
    SCX_ENQ_CPU_SELECTED,

    /**
     * {@code SCX_ENQ_PREEMPT = 4294967296}
     */
    @EnumMember(
        value = 4294967296L,
        name = "SCX_ENQ_PREEMPT"
    )
    SCX_ENQ_PREEMPT,

    /**
     * {@code SCX_ENQ_REENQ = 1099511627776}
     */
    @EnumMember(
        value = 1099511627776L,
        name = "SCX_ENQ_REENQ"
    )
    SCX_ENQ_REENQ,

    /**
     * {@code SCX_ENQ_LAST = 2199023255552}
     */
    @EnumMember(
        value = 2199023255552L,
        name = "SCX_ENQ_LAST"
    )
    SCX_ENQ_LAST,

    /**
     * {@code __SCX_ENQ_INTERNAL_MASK = -72057594037927936}
     */
    @EnumMember(
        value = -72057594037927936L,
        name = "__SCX_ENQ_INTERNAL_MASK"
    )
    __SCX_ENQ_INTERNAL_MASK,

    /**
     * {@code SCX_ENQ_CLEAR_OPSS = 72057594037927936}
     */
    @EnumMember(
        value = 72057594037927936L,
        name = "SCX_ENQ_CLEAR_OPSS"
    )
    SCX_ENQ_CLEAR_OPSS,

    /**
     * {@code SCX_ENQ_DSQ_PRIQ = 144115188075855872}
     */
    @EnumMember(
        value = 144115188075855872L,
        name = "SCX_ENQ_DSQ_PRIQ"
    )
    SCX_ENQ_DSQ_PRIQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_deq_flags"
  )
  public enum scx_deq_flags implements Enum<scx_deq_flags>, TypedEnum<scx_deq_flags, java.lang. @Unsigned Long> {
    /**
     * {@code SCX_DEQ_SLEEP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_DEQ_SLEEP"
    )
    SCX_DEQ_SLEEP,

    /**
     * {@code SCX_DEQ_CORE_SCHED_EXEC = 4294967296}
     */
    @EnumMember(
        value = 4294967296L,
        name = "SCX_DEQ_CORE_SCHED_EXEC"
    )
    SCX_DEQ_CORE_SCHED_EXEC
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_pick_idle_cpu_flags"
  )
  public enum scx_pick_idle_cpu_flags implements Enum<scx_pick_idle_cpu_flags>, TypedEnum<scx_pick_idle_cpu_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_PICK_IDLE_CORE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_PICK_IDLE_CORE"
    )
    SCX_PICK_IDLE_CORE,

    /**
     * {@code SCX_PICK_IDLE_IN_NODE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_PICK_IDLE_IN_NODE"
    )
    SCX_PICK_IDLE_IN_NODE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_kick_flags"
  )
  public enum scx_kick_flags implements Enum<scx_kick_flags>, TypedEnum<scx_kick_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_KICK_IDLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_KICK_IDLE"
    )
    SCX_KICK_IDLE,

    /**
     * {@code SCX_KICK_PREEMPT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_KICK_PREEMPT"
    )
    SCX_KICK_PREEMPT,

    /**
     * {@code SCX_KICK_WAIT = 4}
     */
    @EnumMember(
        value = 4L,
        name = "SCX_KICK_WAIT"
    )
    SCX_KICK_WAIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_tg_flags"
  )
  public enum scx_tg_flags implements Enum<scx_tg_flags>, TypedEnum<scx_tg_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_TG_ONLINE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_TG_ONLINE"
    )
    SCX_TG_ONLINE,

    /**
     * {@code SCX_TG_INITED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_TG_INITED"
    )
    SCX_TG_INITED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_enable_state"
  )
  public enum scx_enable_state implements Enum<scx_enable_state>, TypedEnum<scx_enable_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_ENABLING = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_ENABLING"
    )
    SCX_ENABLING,

    /**
     * {@code SCX_ENABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_ENABLED"
    )
    SCX_ENABLED,

    /**
     * {@code SCX_DISABLING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_DISABLING"
    )
    SCX_DISABLING,

    /**
     * {@code SCX_DISABLED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCX_DISABLED"
    )
    SCX_DISABLED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_ops_state"
  )
  public enum scx_ops_state implements Enum<scx_ops_state>, TypedEnum<scx_ops_state, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_OPSS_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SCX_OPSS_NONE"
    )
    SCX_OPSS_NONE,

    /**
     * {@code SCX_OPSS_QUEUEING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SCX_OPSS_QUEUEING"
    )
    SCX_OPSS_QUEUEING,

    /**
     * {@code SCX_OPSS_QUEUED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_OPSS_QUEUED"
    )
    SCX_OPSS_QUEUED,

    /**
     * {@code SCX_OPSS_DISPATCHING = 3}
     */
    @EnumMember(
        value = 3L,
        name = "SCX_OPSS_DISPATCHING"
    )
    SCX_OPSS_DISPATCHING,

    /**
     * {@code SCX_OPSS_QSEQ_SHIFT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "SCX_OPSS_QSEQ_SHIFT"
    )
    SCX_OPSS_QSEQ_SHIFT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_kick_pseqs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_kick_pseqs extends Struct {
    public callback_head rcu;

    public @Unsigned long @Size(0) [] seqs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dsp_buf_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dsp_buf_ent extends Struct {
    public Ptr<task_struct> task;

    public @Unsigned long qseq;

    public @Unsigned long dsq_id;

    public @Unsigned long enq_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dsp_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dsp_ctx extends Struct {
    public Ptr<rq> rq;

    public @Unsigned int cursor;

    public @Unsigned int nr_tasks;

    public scx_dsp_buf_ent @Size(0) [] buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_bstr_buf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_bstr_buf extends Struct {
    public @Unsigned long @Size(12) [] data;

    public char @Size(1024) [] line;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_dump_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_dump_data extends Struct {
    public int cpu;

    public boolean first;

    public int cursor;

    public Ptr<seq_buf> s;

    public String prefix;

    public scx_bstr_buf buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum scx_dsq_iter_flags"
  )
  public enum scx_dsq_iter_flags implements Enum<scx_dsq_iter_flags>, TypedEnum<scx_dsq_iter_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code SCX_DSQ_ITER_REV = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "SCX_DSQ_ITER_REV"
    )
    SCX_DSQ_ITER_REV,

    /**
     * {@code __SCX_DSQ_ITER_HAS_SLICE = 1073741824}
     */
    @EnumMember(
        value = 1073741824L,
        name = "__SCX_DSQ_ITER_HAS_SLICE"
    )
    __SCX_DSQ_ITER_HAS_SLICE,

    /**
     * {@code __SCX_DSQ_ITER_HAS_VTIME = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "__SCX_DSQ_ITER_HAS_VTIME"
    )
    __SCX_DSQ_ITER_HAS_VTIME,

    /**
     * {@code __SCX_DSQ_ITER_USER_FLAGS = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "__SCX_DSQ_ITER_USER_FLAGS"
    )
    __SCX_DSQ_ITER_USER_FLAGS,

    /**
     * {@code __SCX_DSQ_ITER_ALL_FLAGS = -1073676288}
     */
    @EnumMember(
        value = -1073676288L,
        name = "__SCX_DSQ_ITER_ALL_FLAGS"
    )
    __SCX_DSQ_ITER_ALL_FLAGS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_task_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_task_iter extends Struct {
    public sched_ext_entity cursor;

    public Ptr<task_struct> locked;

    public Ptr<rq> rq;

    public rq_flags rf;

    public @Unsigned int cnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct scx_idle_cpus"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class scx_idle_cpus extends Struct {
    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpu;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> smt;
  }
}
